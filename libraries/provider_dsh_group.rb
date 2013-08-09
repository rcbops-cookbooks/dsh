#
# Cookbook Name:: dsh
# Provider:: group
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

require 'chef/provider'
require 'chef/dsl/data_query'
require "pp"
require "set"

class Chef
  class Provider
    class DshGroup < Chef::Provider
      include Chef::DSL::DataQuery

      def load_current_resource
        @current_resource ||= Chef::Resource::DshGroup.new(new_resource.name)
        @current_resource.group(new_resource.group)
        @current_resource.user(new_resource.user)
        @current_resource.admin_user(new_resource.admin_user)
        @current_resource.admin_pubkey(new_resource.admin_pubkey)
        @current_resource.network(new_resource.network)
        @current_resource.execute(new_resource.execute)
        @current_resource
      end

      def action_join
        if Chef::Config[:solo]
          Chef::Log.warn("The join action uses search. Chef Solo does not support search.")
        end

        install_packages

        # TODO(brett) configure_users() is called regardless of whether
        #     `new_resource' specifies any user attributes or not.  It works
        #     fine (effective noop in the case of nil user attributes), but
        #     seems like it should be put under the conditional below.
        configure_users
        update_host_key

        # If we are a member node,
        # join group by setting attributes ('user' and 'access_name').
        if new_resource.user
          Chef::Log.debug("dsh_group: i'm a member! setting member attributes")
          node.set_unless["dsh"]["groups"][new_resource.name] = {}
          node.set["dsh"]["groups"][new_resource.name]["user"] =
            get_user_name(new_resource.user)

          if new_resource.network
            ip = ::Chef::Recipe::IPManagement.get_ip_for_net(new_resource.network, node)
            Chef::Log.debug("dsh_group: setting access_name to #{ip}")
            node.set["dsh"]["groups"][new_resource.name]["access_name"] = ip
          else
            Chef::Log.debug("dsh_group: setting access_name to #{node['fqdn']}")
            node.set["dsh"]["groups"][new_resource.name]["access_name"] =
              node['fqdn']
          end
        end

        # If we are an admin node,
        # generate pubkey and set admin attributes ('pubkey' and 'admin_user').
        if new_resource.admin_user
          Chef::Log.debug("dsh_group: i'm an admin! setting admin attributes")
          node.set_unless["dsh"]["admin_groups"][new_resource.name] = {}
          user = get_user_name(new_resource.admin_user)
          node.set['dsh']['admin_groups'][new_resource.name]['admin_user'] = user
          configure_pubkey(get_home(user), user)  # sets node attribute
        end

        #########################################################################
        # Now that our node attributes are set, proceed with node searches and
        # generate openssh/dsh files
        #########################################################################

        # Find all admin nodes and write their pubkeys to authorized_keys
        if new_resource.user
          # read existing keys from file
          user = get_user_name(new_resource.user)
          home = get_home(user)
          file = "#{home}/.ssh/authorized_keys"
          keys = Set.new(::File.read(file).split(/\n/))

          # collect keys from admin nodes
          group_keys = find_dsh_group_admins(new_resource.name).collect do |n|
            n['dsh']['admin_groups'][new_resource.name]['pubkey']
          end

          # fetch keys previously persisted to chef server
          old_keys = node['dsh']['groups'][new_resource.name]['authorized_keys'] || []

          # find stale keys from old hosts
          stale_keys = old_keys - group_keys

          Chef::Log.debug("dsh_group: search results for admin keys: #{group_keys}")
          Chef::Log.debug("dsh_group: local keys from #{file}: #{keys.inspect}")
          Chef::Log.debug("dsh_group: previously cached keys: #{old_keys}")
          Chef::Log.debug("dsh_group: stale keys: #{stale_keys}")

          # purge stale keys
          keys -= stale_keys

          # graft in current admin keys
          # ('keys' is a Set; won't contain dups)
          keys += group_keys

          # persist current admin keys back to server
          node.set['dsh']['groups'][new_resource.name]['authorized_keys'] = group_keys

          # write the authorized_keys file
          Chef::Log.debug("dsh_group: writing admin keys to #{file}: #{keys.inspect}")
          f = file "#{home}/.ssh/authorized_keys" do
            owner user
            group user
            content keys.collect { |k| k }.join("\n")
          end
          f.run_action(:create)
        end # if new_resource.user

        # Find all members and write them to known_hosts and .dsh/group/
        if new_resource.admin_user
          user = get_user_name(new_resource.admin_user)
          home = get_home(user)
          ssh_file = "#{home}/.ssh/known_hosts"

          dsh_dot_dir = ::File.join(home, '.dsh')
          dsh_group_dir = ::File.join(dsh_dot_dir, 'group')
          dsh_group_file = ::File.join(dsh_group_dir, new_resource.name)

          # create directories with correct permissions
          [dsh_dot_dir, dsh_group_dir].each do |dir|
            d = directory dir do
              owner user
              group user
            end
            d.run_action(:create)
          end

          members = find_dsh_group_members(new_resource.name)
          Chef::Log.debug("dsh_group: search results for group members: #{members}")

          hosts = []
          members.each do |n|
            hosts << {
              "name" => n['dsh']['groups'][new_resource.name]['access_name'],
              "key" => n['dsh']['host_key']
            }
          end
          # TODO(brett) should this be nested under group name key?
          # TODO(brett) add logic for multiple dsh groups
          node.set['dsh']['hosts'] = hosts

          # Add new hosts to known_hosts
          Chef::Log.debug("dsh_group: opening #{ssh_file} in append mode")
          f = ::File.new(ssh_file, "a")
          hosts.each do |h|
            #if `su #{user} -c 'ssh-keygen -F #{h['name']}' | wc -l`.strip == "0"
            if known_hosts_contains?(user, h["name"])
              Chef::Log.info("Adding known host #{h['name']} to #{f.path}")
              f.write("#{h['name']} #{h['key']}\n")
            end
          end
          f.close()

          # Configure .dsh/group/<file>
          f = file dsh_group_file do
            owner user
            group user
            content members.collect { |n|
              "#{n['dsh']['groups'][new_resource.name]['user']}@" +
                "#{n['dsh']['groups'][new_resource.name]['access_name']}\n"
            }.sort.join
          end
          f.run_action(:create)
        end # if new_resource.admin_user

        Chef::Log.debug("dsh_group: Howdy from :join -- new_resource: #{PP.pp(new_resource, dump='')}" +
          ", current_resource: #{PP.pp(current_resource, dump='')}")
      end

      def action_execute
        admin_user = node["dsh"]["admin_groups"][new_resource.name]["admin_user"]
        home = get_home(admin_user)
        group_file = "#{home}/.dsh/group/#{new_resource.name}"

        if node.platform_family?("rhel")
          pssh_cmd="pdsh"
          pssh_opt="-g #{new_resource.name}"
        elsif node.platform_family?("debian")
          pssh_cmd="parallel-ssh"
          pssh_opt="-h #{group_file} -p 32 -t 120"
        end

        cmd = "#{pssh_cmd} #{pssh_opt} #{shell_escape(new_resource.execute)}"
        Chef::Log.info("Executing #{cmd} as #{admin_user}")
        execute cmd do
          user admin_user
          only_if "wc -l #{group_file} | grep -v '^0 '"
        end
      end

      private

      def install_packages
        platform_options=node["pssh"]["platform"]
        platform_options["pssh_packages"].each do |pkg|
          package pkg do
            action :install
            options platform_options["package_overrides"]
          end
        end
      end

      def known_hosts_contains?(username, hostname)
        return `su #{username} -c 'ssh-keygen -F #{hostname}' | wc -l`.strip == "0"
      end

      def update_host_key()
        host_key = ::File.read("/etc/ssh/ssh_host_rsa_key.pub").strip
        if host_key != node["dsh"]["host_key"]
          Chef::Log.info("Updating host key to #{host_key}")
          node.set["dsh"]["host_key"] = host_key
          new_resource.updated_by_last_action(true)
        end
      end

      def find_dsh_group_members(name)
        results = search(
          :node,
          "dsh_groups:#{new_resource.name} AND chef_environment:#{node.chef_environment}"
        )
        # add ourself to the list if necessary
        if node['dsh']['groups'].key?(new_resource.name)
          if not results.map(&:name).include?(node.name)
            Chef::Log.debug("dsh_group: #{__method__}: " +
              "i appear to be a group member, adding myself to search results")
            results << node
          end
        end
        results
      end

      def find_dsh_group_admins(name)
        results = search(
          :node,
          "dsh_admin_groups:#{new_resource.name} AND chef_environment:#{node.chef_environment}"
        )
        # add ourself to the list if necessary
        if node['dsh']['admin_groups'].key?(new_resource.name)
          if not results.map(&:name).include?(node.name)
            Chef::Log.debug("dsh_group: #{__method__}: " +
              "i appear to be a group admin, adding myself to search results")
            results << node
          end
        end
        results
      end

      def get_home(username)
        ::File.expand_path "~#{username}"
      end

      def configure_pubkey(home, username)
        privkey_path = "#{home}/.ssh/id_rsa"
        pubkey_path  = "#{home}/.ssh/id_rsa.pub"
        priv = ::File.exists?(privkey_path)
        pub  = ::File.exists?(pubkey_path)

        if priv and not pub
          Chef::Log.info("Generating pubkey for #{privkey_path}")
          system("su #{username} -c 'ssh-keygen -y -f #{privkey_path} > #{pubkey_path}'")
          new_resource.updated_by_last_action(true)
        elsif pub and not priv
          Chef::Application.fatal!(
            "#{pubkey_path} exists, but its private key is missing.  " +
              "Either create the matching #{privkey_path} file or remove #{pubkey_path}"
          )
        elsif not pub and not priv
          Chef::Log.info("Generating ssh keys for user #{username} from #{privkey_path} and #{pubkey_path}")
          system(
            "su #{username} -c 'ssh-keygen -q -f #{privkey_path} " +
              "-P \"\"'", :in=>"/dev/null"
          )
          new_resource.updated_by_last_action(true)
        end

        pubkey = ::File.read(pubkey_path).strip
        if pubkey != node['dsh']['admin_groups'][new_resource.name]['pubkey']
          Chef::Log.info("Setting `pubkey' node attribute (user key for admin " +
            "`#{username}') to: #{pubkey}")
          node.set['dsh']['admin_groups'][new_resource.name]['pubkey'] = pubkey
        end
      end

      def shell_escape(s)
        return "'" + s.gsub(/\'/, "'\"'\"'") + "'"
      end

      def configure_users()
        users = {}
        [new_resource.user, new_resource.admin_user].compact.map do |user|
          users[get_user_name(user)] = get_user_options(user)
        end

        users.each do |u, o|
          # TODO(wilk): fix this section
          # special cases for root and nova users.  Do not create either
          # of these users
          unless node['dsh']['skip_create'].include?(u)
            user_p = user u do
              shell "/bin/bash"
              home "/home/#{u}"
            end
            o.each { |k, v| user_p.send(k, v) if user_p.respond_to?(k) }
            user_p.run_action(:create)

            home = get_home(u)
            d = directory home do
              owner u
              group u
              mode 0700
            end
            d.run_action(:create)
          else
            home = get_home(u)
          end # unless node['dsh']['skip_create'].include?(u)

          create_ssh_directories(u, home)
        end # users.each
      end

      def create_ssh_directories(user, home)
        d = directory "#{home}/.ssh" do
          owner user
          group user
        end
        d.run_action(:create)

        ["#{home}/.ssh/authorized_keys", "#{home}/.ssh/known_hosts"].each do |i|
          f = file i do
            owner user
            group user
          end
          f.run_action(:create)
        end
      end

      def get_user_name(user)
        if user.kind_of?(Hash)
          user["username"] || user[:username] || user["name"] || user[:name]
        else
          user
        end
      end

      def get_user_options(user)
        if user.kind_of?(Hash)
          user.to_hash
        else
          {}
        end
      end

    end
  end
end
