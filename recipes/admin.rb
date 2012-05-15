dsh_group "testing" do
  admin_user "root"
  network "swift"
end

dsh_group "testing" do
  execute "hostname"
  action :execute
end
