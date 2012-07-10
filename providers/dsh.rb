require 'set'

if Chef::Config[:solo]
  Chef::Log.warn("This recipe uses search. Chef Solo does not support search.")
end

action :join do
  Package "dsh" do
    only_if { new_resource.admin_user}
    action :upgrade
  end

  configure_users
  update_host_key
  admins = find_dsh_group_admins(new_resource.name)
  members = find_dsh_group_members(new_resource.name)
  
  if new_resource.user
    #Member node: allow logins from admin_users
    #Join group by setting appropriate attributes
    node["dsh"]["groups"][new_resource.name] = {}
    node["dsh"]["groups"][new_resource.name]["user"] = new_resource.user
    node["dsh"]["groups"][new_resource.name]["access_name"] = node['fqdn']
    if new_resource.network
      node["dsh"]["groups"][new_resource.name]["access_name"] = 
        ::Chef::Recipe::IPManagement.get_ip_for_net(new_resource.network, node)
    end
    home = get_home(new_resource.user)
    auth_key_file = "#{home}/.ssh/authorized_keys"
    authorized = []
    
    #configure authorized_keys
    keys = Set.new(::File.new(auth_key_file, "r").read().split(/\n/))
    group_keys = admins.collect() do |n|
      n['dsh']['admin_groups'][new_resource.name]['pubkey']
    end
    keys += group_keys
    node['dsh']['groups'][new_resource.name]['authorized_keys'] ||= []
    old_keys = node['dsh']['groups'][new_resource.name]['authorized_keys']

    #don't write keys previously in the group that no longer exist.
    keys -= (old_keys - group_keys)
    f = file "#{home}/.ssh/authorized_keys" do
        owner new_resource.user
        group new_resource.user
        content keys.collect {|k| k}.join("\n")
        action :create
    end
    f.run_action(:create)
    node['dsh']['groups'][new_resource.name]['authorized_keys'] = group_keys

    new_resource.updated_by_last_action(true)
  end
  
  if new_resource.admin_user
    #Admin node configure ability to log in to members.
    home = get_home(new_resource.admin_user)
    get_pubkey(home)
    new_resource.updated_by_last_action(true)

    #Remove hosts that are no longer in the list
    old_hosts = node['dsh']['hosts']
    hosts = []
    members.each do |n| 
      hosts << {"name" => n['dsh']['groups'][new_resource.name]['access_name'],
        "key" => n['dsh']['host_key']}
    end
    remove_hosts = old_hosts - hosts
    remove_hosts.each do |h| 
      execute "ssh-keygen -R #{h['name']}" do
        Chef::Log.info("Removing known host #{h['name']}")
        user new_resource.admin_user
      end
    end

    #Add new hosts to known_hosts
    f = ::File.new("#{home}/.ssh/known_hosts", "a")
    hosts.each do |h|
      if `su #{new_resource.admin_user} -c 'ssh-keygen -F #{h['name']}' | wc -l`.strip == "0"
        Chef::Log.info("Adding known host #{h['name']}")
        f.write("#{h['name']} #{h['key']}\n")
      end
    end
    f.close()
    node['dsh']['hosts'] = hosts 

    #Configure dsh
    f = ::File.new("#{home}/.dsh/group/#{new_resource.name}", "w")
    members.each do |n|
      Chef::Log.info("Adding #{n.name} to dsh group #{new_resource.name}")
      f.write("#{n['dsh']['groups'][new_resource.name]['user']}@" +
              "#{n['dsh']['groups'][new_resource.name]['access_name']}\n")
    end
    f.close()
  end

end

def update_host_key()
  host_key = ::File.read("/etc/ssh/ssh_host_rsa_key.pub").strip
  if host_key != node["dsh"]["host_key"]
    Chef::Log.info("Updating host key to #{host_key}")
    node["dsh"]["host_key"] = host_key
    new_resource.updated_by_last_action(true)
  end
end

def find_dsh_group_members(name)
  return search(:node, "dsh_groups:#{new_resource.name} AND " +
                "chef_environment:#{node.chef_environment}")
end

def find_dsh_group_admins(name)
  return search(:node, "dsh_admin_groups:#{new_resource.name} " +
                "AND chef_environment:#{node.chef_environment}")
end

def get_home(user)
  ::File.expand_path "~#{user}"
end

def get_pubkey(home)
  privkey_path = "#{home}/.ssh/id_rsa"
  pubkey_path = "#{privkey_path}.pub"
  if not (::File.exists? privkey_path or ::File.exists? pubkey_path)
    Chef::Log.info("Generating ssh keys for user #{new_resource.admin_user}")
    system("su #{new_resource.admin_user} -c 'ssh-keygen -q -f #{privkey_path} " +
           "-P \"\"'", :in=>"/dev/null")
    new_resource.updated_by_last_action(true)
  end
  pubkey = ::File.read("#{home}/.ssh/id_rsa.pub").strip
  node["dsh"]["admin_groups"][new_resource.name] ||= {}
  if pubkey != node["dsh"]["admin_groups"][new_resource.name]["pubkey"]
    Chef::Log.info("Updating pubkey for admin_user #{new_resource.admin_user}")
    node["dsh"]["admin_groups"][new_resource.name] = {
      "user" => new_resource.admin_user,
      "pubkey" => pubkey
    }
  end
end

def configure_users()
  users = []
  users << new_resource.user if new_resource.user
  users << new_resource.admin_user if new_resource.admin_user
  users.each { |u|
    # TODO(wilk): fix this section
    # special cases for root and nova users.  Do not create either
    # of these users
    if not (u == "root" or u == "nova")
        user_p = user u do
        shell "/bin/bash"
        home "/home/#{u}"
      end
      user_p.run_action(:create)
      home = get_home(u)
      rs = []
      d = directory home do
        owner u
        group u
        mode 0700
        action :create
      end
      d.run_action(:create)
    else
      home = get_home(u)
    end
    d = directory "#{home}/.ssh" do
      owner u
      group u
      action :create
    end
    d.run_action(:create)
    home = get_home(u)
    ["#{home}/.ssh/authorized_keys", "#{home}/.ssh/known_hosts"].each do |i|
      f = file i do
        owner u
        group u
        action :create
      end
      f.run_action(:create)
    end
    d = directory "#{home}/.dsh/group" do
      only_if { u == new_resource.admin_user}
      owner u
      group u
      recursive true
      action :create
    end
    d.run_action(:create)
    f = file "#{home}/.dsh/group/#{new_resource.name}" do
      only_if { u == new_resource.admin_user}
      owner u
      group u
      action :create
    end
    f.run_action(:create)
  }
end

action :execute do
end
