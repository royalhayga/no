#!/usr/bin/env ruby

require 'yaml'
require 'fileutils'

CONFIG_FILE = ARGV[0] || "/etc/openclash/config/config.yaml"

begin
  # 1. 备份原配置
  FileUtils.cp(CONFIG_FILE, "#{CONFIG_FILE}.bak")

  # 2. 读取当前 OpenClash 运行中的配置
  conf = YAML.load_file(CONFIG_FILE) || {}

  # 3. 注入 Proxy-Provider (指向 GitHub 纯净节点池)
  conf['proxy-providers'] ||= {}
  conf['proxy-providers']['github_free_nodes'] = {
    'type' => 'http',
    'url' => 'https://raw.githubusercontent.com/royalhayga/no/master/output/clash.yaml',
    'path' => './proxy_providers/github_free_nodes.yaml',
    'interval' => 21600,
    'health-check' => {
      'enable' => true,
      'interval' => 300,
      'url' => 'http://www.gstatic.com/generate_204'
    }
  }

  # 4. 把 provider 挂载到策略组 (排除含有"直连"、"广告"、"屏蔽"的特殊组)
  if conf['proxy-groups'].is_a?(Array)
    conf['proxy-groups'].each do |group|
      next unless group.is_a?(Hash)
      gname = group['name'] || ""

      # 避免干扰本地直连或广告屏蔽组
      if !gname.include?("直连") && !gname.include?("广告") && !gname.include?("拦截")
        group['use'] ||= []
        group['use'] << 'github_free_nodes'
        group['use'].uniq!
      end
    end
  end

  # 5. 写回修改后的配置
  File.open(CONFIG_FILE, 'w') { |f| f.write(YAML.dump(conf)) }
  puts "OpenClash 动态合并成功：已成功挂载 GitHub 纯节点池至 Proxy-Provider！"
rescue Exception => e
  puts "合并失败: #{e.message}"
  exit 1
end
