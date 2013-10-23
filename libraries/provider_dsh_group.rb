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
        @current_resource.skip_create(new_resource.skip_create)
        @current_resource
      end

      # action :join
      def action_join
        if Chef::Config[:solo]
          Chef::Log.warn("The join action uses search. Chef Solo does not support search.")
        end

        # Install the required packages
        install_packages

        # Update the host key attribute from sshd files
        update_host_key_attribute

        # Create the user/admin_user accounts
        create_users

        # If specified, add the user and access information to the group
        if new_resource.user
          configure_user_attribute
          configure_access_name_attribute
        end

        # If specified, add the admin user to the group with pubkeys
        if new_resource.admin_user
          create_dsh_directories
          configure_admin_user_attribute
          configure_pubkey_attribute
        end

        #########################################################################
        # Now that our node attributes are set, proceed with node searches and
        # generate openssh/dsh files
        #########################################################################

        # Find all admin nodes and write their pubkeys to the users authorized_keys
        if new_resource.user
          add_admin_nodes_to_authorized_keys
        end

        # Find all member nodes and write them to the admin users known_hosts and .dsh/group$group file
        if new_resource.admin_user
          add_member_nodes_to_known_hosts
        end

        Chef::Log.debug("dsh_group: new_resource: #{PP.pp(new_resource, dump='')}, " +
          "current_resource: #{PP.pp(current_resource, dump='')}")
      end

      # action :execute
      def action_execute
        admin_user = node["dsh"]["admin_groups"][group_name]["admin_user"]
        home = get_user_home(admin_user)
        group_file = "#{home}/.dsh/group/#{group_name}"

        if node.platform_family?("rhel")
          pssh_cmd="pdsh"
          pssh_opt="-g #{group_name}"
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

      # Returns the name of the group being configured
      def group_name
        new_resource.group || new_resource.name
      end

      # Installs the packages specified in /pssh/platform/pssh_packages
      # using any options in /pssh/platform/pssh_options
      def install_packages
        platform_options=node["pssh"]["platform"]
        platform_options["pssh_packages"].each do |pkg|
          begin
            resource_collection.find(:package => pkg)
          rescue Chef::Exceptions::ResourceNotFound
            package pkg do
              action :install
              options platform_options["package_options"]
            end
          end
        end
      end

      # Creates the user/admin_user, home, and ssh directories
      # It will skip creation for any user names specified in the skip_create resource attribute
      def create_users()
        users = {}
        [new_resource.user, new_resource.admin_user].compact.map do |user|
          users[get_user_name(user)] = get_user_options(user)
        end

        users.each do |u, o|
          unless new_resource.skip_create.include?(u)
            begin
              user_p = resource_collection.find(:user => u)
            rescue Chef::Exceptions::ResourceNotFound
              user_p = user(u)
            end
            user_p.instance_exec do
              shell "/bin/bash"
              home "/home/#{u}"
            end
            o.each { |k, v| user_p.send(k, v) if user_p.respond_to?(k) }
            user_p.run_action(:create)

            home = get_user_home(u)
            begin
              d = resource_collection.find(:directory => home)
            rescue Chef::Exceptions::ResourceNotFound
              d = directory(home)
            end
            d.instance_exec do
              owner u
              group u
              mode 0700
            end
            d.run_action(:create)
          else
            home = get_user_home(u)
          end

          create_ssh_directories(u, home)
        end
      end

      # Creates the ssh directory and authorized_keys/known_hosts files for a user
      def create_ssh_directories(username, home)
        ssh_dir = "#{home}/.ssh"
        begin
          d = resource_collection.find(:directory => ssh_dir)
        rescue Chef::Exceptions::ResourceNotFound
          d = directory(ssh_dir)
        end
        d.instance_exec do
          owner username
          group username
        end
        d.run_action(:create)

        ["#{home}/.ssh/authorized_keys", "#{home}/.ssh/known_hosts"].each do |i|
          begin
            f = resource_collection.find(:file => i)
          rescue Chef::Exceptions::ResourceNotFound
            f = file(i)
          end
          f.instance_exec do
            owner username
            group username
          end
          f.run_action(:create)
        end
      end

      # Updates /dsh/host_key attribute from ssh_host_rsa_key.pub if it is empty or different
      def update_host_key_attribute
        host_key = ::File.read("/etc/ssh/ssh_host_rsa_key.pub").strip

        if not node["dsh"] or host_key != node["dsh"]["host_key"]
          Chef::Log.info("Updating host key to #{host_key}")

          node.set["dsh"]["host_key"] = host_key

          new_resource.updated_by_last_action(true)
        end
      end

      # Adds/updates the user name in /dsh/groups/$group/user
      def configure_user_attribute
        username = get_user_name(new_resource.user)

        Chef::Log.debug("dsh_group: adding user '#{username}' to '#{group_name}'")

        node.set_unless["dsh"]["groups"][group_name] = {}
        node.set["dsh"]["groups"][group_name]["user"] = username
      end

      # Adds/updates the admin user name in /dsh/admin_groups/$group/admin_user
      def configure_admin_user_attribute
        username = get_user_name(new_resource.admin_user)

        Chef::Log.debug("dsh_group: adding admin '#{username}' to '#{group_name}'")

        node.set_unless["dsh"]["admin_groups"][group_name] = {}
        node.set["dsh"]["admin_groups"][group_name]["admin_user"] = username
      end

      # Adds/updates the access_name attribute in /dsh/groups/$group/access_name
      def configure_access_name_attribute
        access_name = if new_resource.network
          Chef::Recipe::IPManagement.get_ip_for_net(new_resource.network, node)
        else
          node["fqdn"]
        end

        Chef::Log.debug("dsh_group: setting access_name to '#{access_name}'")

        node.set_unless["dsh"]["admin_groups"][group_name] = {}
        node.set["dsh"]["groups"][group_name]["access_name"] = access_name
      end

      # Adds/updates the ssh pubkey attribute in /dsh/admin_groups/$group/pubkey
      # from the admin users ssh directory
      def configure_pubkey_attribute
        username = get_user_name(new_resource.admin_user)
        home = get_user_home(username)

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

          system("su #{username} -c 'ssh-keygen -q -f #{privkey_path} -P \"\"'", :in=>"/dev/null")

          new_resource.updated_by_last_action(true)
        end

        pubkey = ::File.read(pubkey_path).strip
        if pubkey != node["dsh"]["admin_groups"][group_name]["pubkey"]
          Chef::Log.info("Setting `pubkey' node attribute (user key for admin " +
            "`#{username}') to: #{pubkey}")
          node.set['dsh']['admin_groups'][group_name]['pubkey'] = pubkey
        end
      end

      # Add admin nodes pubkeys to the users authorized_keys file
      def add_admin_nodes_to_authorized_keys
        # read existing keys from file
        user = get_user_name(new_resource.user)
        home = get_user_home(user)
        file_name = "#{home}/.ssh/authorized_keys"
        keys = Set.new(::File.read(file_name).split(/\n/))

        # collect keys from admin nodes
        group_keys = find_dsh_group_admins.collect do |n|
          n["dsh"]["admin_groups"][group_name]["pubkey"]
        end

        # fetch keys previously persisted to chef server
        old_keys = node["dsh"]["groups"][group_name]["authorized_keys"] || []

        # find stale keys from old hosts
        stale_keys = old_keys - group_keys

        Chef::Log.debug("dsh_group: search results for admin keys: #{group_keys}")
        Chef::Log.debug("dsh_group: local keys from #{file_name}: #{keys.inspect}")
        Chef::Log.debug("dsh_group: previously cached keys: #{old_keys}")
        Chef::Log.debug("dsh_group: stale keys: #{stale_keys}")

        # purge stale keys
        keys -= stale_keys

        # graft in current admin keys
        # ('keys' is a Set; won't contain dups)
        keys += group_keys

        # persist current admin keys back to server
        node.set["dsh"]["groups"][group_name]["authorized_keys"] = group_keys

        # write the authorized_keys file
        Chef::Log.debug("dsh_group: writing admin keys to #{file_name}: #{keys.inspect}")
        begin
          f = resource_collection.find(:file => file_name)
        rescue Chef::Exceptions::ResourceNotFound
          f = file(file_name)
        end
        f.instance_exec do
          owner user
          group user
          content keys.collect { |key| key }.join("\n")
        end
        f.run_action(:create)
      end

      # creates dsh group directories for admin user
      def create_dsh_directories
        user = get_user_name(new_resource.admin_user)
        home = get_user_home(user)
        dsh_dot_dir = ::File.join(home, '.dsh')
        dsh_group_dir = ::File.join(dsh_dot_dir, 'group')

        # create directories with correct permissions
        [dsh_dot_dir, dsh_group_dir].each do |dir|
          begin
            d = resource_collection.find(:directory => dir)
          rescue Chef::Exceptions::ResourceNotFound
            d = directory(dir)
          end
          d.instance_exec do
            owner user
            group user
          end
          d.run_action(:create)
        end
      end

      # Adds member nodes host keys to known hosts and members to group file
      def add_member_nodes_to_known_hosts
        user = get_user_name(new_resource.admin_user)
        home = get_user_home(user)
        ssh_file = "#{home}/.ssh/known_hosts"

        members = find_dsh_group_members
        Chef::Log.debug("dsh_group: search results for group members: #{members}")

        hosts = []
        members.each do |n|
          hosts << {
            "name" => n['dsh']['groups'][group_name]['access_name'],
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

        add_member_nodes_to_group_file(members)
      end

      # add list of nodes /dsh/groups/$group/user and access_name to group file
      def add_member_nodes_to_group_file(nodes)
        user = get_user_name(new_resource.admin_user)
        home = get_user_home(user)
        dsh_group_file = ::File.join(home, ".dsh", "group", group_name)

        group_name = self.group_name

        f = file dsh_group_file do
          owner user
          group user
          content nodes.collect { |n|
            "#{n['dsh']['groups'][group_name]['user']}@" +
              "#{n['dsh']['groups'][group_name]['access_name']}\n"
          }.sort.join
        end
        f.run_action(:create)
      end

      # Determines if the users known_hosts contains the specified hostname
      def known_hosts_contains?(username, hostname)
        return `su #{username} -c 'ssh-keygen -F #{hostname}' | wc -l`.strip == "0"
      end

      # Returns the member nodes for the current group and adds self if necessary
      def find_dsh_group_members
        results = search(
          :node,
          "dsh_groups:#{group_name} AND chef_environment:#{node.chef_environment}"
        )
        # add ourself to the list if necessary
        if node["dsh"]["groups"].key?(group_name)
          if not results.map(&:name).include?(node.name)
            Chef::Log.debug("dsh_group: #{__method__}: " +
              "i appear to be a group member, adding myself to search results")
            results << node
          end
        end
        results
      end

      # Returns the admin nodes for the current group and adds self if necessary
      def find_dsh_group_admins
        results = search(
          :node,
          "dsh_admin_groups:#{group_name} AND chef_environment:#{node.chef_environment}"
        )
        # add ourself to the list if necessary
        if node["dsh"]["admin_groups"].key?(group_name)
          if not results.map(&:name).include?(node.name)
            Chef::Log.debug("dsh_group: #{__method__}: i appear to be a group admin, adding myself to search results")
            results << node
          end
        end
        results
      end

      # Returns the home directory for the specified user name
      def get_user_home(username)
        ::File.expand_path "~#{username}"
      end

      # Returns the user name for the specified user resource attribute
      #
      # This can be either a string, or a hash containing attributes to be
      # passed into the user resource being created
      def get_user_name(user)
        if user.kind_of?(Hash)
          user["username"] || user[:username] || user["name"] || user[:name]
        else
          user
        end
      end

      # Returns the user options for the specified user resource attribute
      def get_user_options(user)
        if user.kind_of?(Hash)
          user.to_hash
        else
          {}
        end
      end

      # Returns an escaped shell command
      # TODO: maybe use the shell out chef mixin?
      def shell_escape(command)
        return "'" + command.to_s.gsub(/\'/, "'\"'\"'") + "'"
      end

    end
  end
end
