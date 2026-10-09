#!/usr/bin/env ruby

require 'yaml'
require 'fileutils'
require 'open-uri'

# OpenClash 传入的当前将要启动的配置文件路径 (Public 蓝本)
CONFIG_FILE = ARGV[0] || "/etc/openclash/config/config.yaml"
# 您的独立私有节点订阅链接
PRIVATE_URL = "https://umail.eu.org:2096/clash/e86jzn5fd9btwai4"
PRIVATE_YAML_PATH = "/tmp/private_seal_sub.yaml"
CONFIG_BAK = "/etc/openclash/config/config.yaml.last_good.bak"

def log_msg(msg)
  time_str = Time.now.strftime("%Y-%m-%d %H:%M:%S")
  File.open("/tmp/openclash.log", "a") { |f| f.puts("#{time_str} [TVTV Mixin] #{msg}") }
end

begin
  log_msg("开始执行动态节点合并脚本...")

  # 1. 下载私有节点订阅到临时文件 (5秒超时防卡死)
  begin
    URI.open(PRIVATE_URL, read_timeout: 5) do |remote|
      File.open(PRIVATE_YAML_PATH, 'w') { |file| file.write(remote.read) }
    end
    log_msg("私有节点拉取成功")
  rescue StandardError => e
    log_msg("警告：私有节点拉取失败 (#{e.message})，将仅使用 Public 原生配置")
    exit 0
  end

  # 2. 读取当前 Public 配置与拉取到的 Private 配置
  conf = YAML.load_file(CONFIG_FILE) || {}
  priv = YAML.load_file(PRIVATE_YAML_PATH) || {}

  conf_proxies = conf['proxies'] || []
  priv_proxies = priv['proxies'] || []

  if !priv_proxies.empty?
    # 3. 建立私有节点的名称 Map 字典
    priv_map = {}
    priv_proxies.each do |p|
      if p.is_a?(Hash) && p['name'] && !p['name'].to_s.strip.empty?
        priv_map[p['name'].to_s.strip] = p
      end
    end

    priv_names = priv_map.keys

    # 4. 精准剔除 Public 蓝本中的同名节点（包括占位符），防止内核抛 duplicate name 崩溃
    clean_conf_proxies = conf_proxies.reject do |p|
      p.is_a?(Hash) && p['name'] && priv_map.key?(p['name'].to_s.strip)
    end

    # 5. 将真实的私有节点前置插入到代理节点数组开头
    conf['proxies'] = priv_proxies + clean_conf_proxies

    # 6. 精准置顶注入到各个指定的业务策略组 (proxy-groups)
    if conf['proxy-groups'].is_a?(Array)
      conf['proxy-groups'].each do |group|
        next unless group.is_a?(Hash)
        gname = group['name'] || ""
        current_p = group['proxies'] || []

        # 在这些核心策略组中，将私有节点名字强制塞到第一顺位
        target_groups = ['PROXY', '📺 TVBox代理', '🎬 国外影视', '🟢 OpenAI', '▶️ YouTube', '🌐 Google', '✈️ Telegram', '🐦 Twitter / X', '🍿 流媒体/Netflix', '🐙 GitHub / Docker', '🍎 Apple', '🪟 Microsoft', '🎮 Steam / 游戏']

        if target_groups.include?(gname) || gname.include?('银行')
          # 将私有节点放置于顶部，再拼接原有节点，最后 uniq 去重保持顺序
          group['proxies'] = (priv_names + current_p).uniq
        end
      end
    end

    # 7. 写回合并后的终极 YAML 配置
    File.open(CONFIG_FILE, 'w') { |f| f.write(YAML.dump(conf)) }
    log_msg("私有节点已成功精准覆盖并置顶注入到策略组！")
  else
    log_msg("警告：拉取到的私有节点内容为空")
  end

rescue Exception => e
  log_msg("致命错误：节点合并覆写失败: #{e.message}")
  exit 1
end
