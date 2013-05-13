Pod::Spec.new do |s|
  s.name         = "SimpleSecrets"
  s.version      = "1.0.0"
  s.summary      = "A simple, opinionated library for encrypting small packets of data."
  s.homepage     = "https://github.com/timshadel/SimpleSecrets"
  s.author       = { "Tim Shadel" => "tim@shadelsoftware.com" }
  s.source       = { :git => "https://github.com/timshadel/SimpleSecrets.git", :tag => "1.0.0" }
  s.ios.deployment_target = '5.0'
  s.osx.deployment_target = '10.7'
  s.source_files = 'SimpleSecrets/**/*.{h,m}'
  s.public_header_files = 'SimpleSecrets/**/SimpleSecrets.h'
  s.framework  = 'Security'
  s.library   = 'crypto'
  s.requires_arc = true
  s.dependency 'MessagePack', '~> 1.0'
end
