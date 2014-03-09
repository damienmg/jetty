#
# Cookbook Name:: jetty
# Recipe:: iptables
#
# Copyright 2013, Opscode, Inc.
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

include_recipe "iptables"

if node[:jetty][:ssl_cert] then
  ssl_cert = data_bag_item('certificates', node[:jetty][:ssl_cert])
else
  fqdn_search = "fqdn:#{node[:fqdn]}"
  ssl_cert = search(:certificates, fqdn_search).first
end

iptables_rule "port_jetty" do 
  variables({"ssl_cert" => ssl_cert})
end

package "authbind" do
  action :install
end

if node['jetty']['port'] <= 1024 then
  file "/etc/authbind/byport/#{node['jetty']['port']}" do
    user node['jetty']['user']
    group node['jetty']['group']
    mode "0700"
    action :touch
  end
end
if node['jetty']['ssl_port'] and (node['jetty']['ssl_subject'] or ssl_cert) and node['jetty']['ssl_port'] <= 1024 then
  # Install authbind
  file "/etc/authbind/byport/#{node['jetty']['ssl_port']}" do
    user node['jetty']['user']
    group node['jetty']['group']
    mode "0700"
    action :touch
  end
end
