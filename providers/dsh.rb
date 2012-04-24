action :join do
  execute "allow access" do
    only_if new_resource.user
    command "touch /tmp/#{new_resource.user}"
  end
end

action :leave do
  execute "revoke access" do
    command "rm /tmp/#{new_resource.user}"
  end
end
