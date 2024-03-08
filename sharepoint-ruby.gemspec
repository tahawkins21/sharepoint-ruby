Gem::Specification.new do |s|
  s.name         = 'sharepoint-ruby'
  s.version      = '0.2.2'
  s.date         = '2022-04-25'
  s.summary      = 'sharepoint client'
  s.description  = "Client for Sharepoint's REST API"
  s.authors      = ["Michael Martin Moro"]
  s.email        = 'michael@unetresgrossebite.com'
  s.files        = Dir["lib/**/*", "MIT-LICENSE", "README.md"]
  s.homepage     = 'https://github.com/tahawkins21/sharepoint-ruby'
  s.license      = '0BSD'
  s.require_path = 'lib'

 # s.add_runtime_dependency 'curb', '~> 0.8', '<= 1.0.5'
 s.add_runtime_dependency 'curb', '= 1.0.5'
end
