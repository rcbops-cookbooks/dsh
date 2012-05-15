dsh_group "testing" do
  admin_user "root"
end

dsh_group "testing" do
  execute "hostname"
end
