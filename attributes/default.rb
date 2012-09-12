default["dsh"]["groups"] = {}               # node_attribute
default["dsh"]["admin_groups"] = {}         # node_attribute
default["dsh"]["host_key"] = ""             # node_attribute
default["dsh"]["hosts"] = []                # node_attribute

case platform
when "fedora", "redhat", "centos"
  default["pssh"]["platform"] = {
    "pssh_packages" => ["pdsh-mod-dshgroup"]
  }
when "ubuntu"
  default["pssh"]["platform"] = {
    "pssh_packages" => ["pssh"]
  }
end
